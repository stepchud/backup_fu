require 'yaml'
require 'active_support'
require 'mime/types'
require 'right_aws'
require 'erb'

class BackupFuConfigError < StandardError; end
class S3ConnectError < StandardError; end

class BackupFu
  attr_accessor :archive_path

  def initialize
    db_conf = YAML.load_file(File.join(RAILS_ROOT, 'config', 'database.yml')) 
    @db_conf = db_conf[RAILS_ENV].symbolize_keys

    raw_config = File.read(File.join(RAILS_ROOT, 'config', 'backup_fu.yml'))
    erb_config = ERB.new(raw_config).result
    fu_conf    = YAML.load(erb_config)
    @fu_conf   = fu_conf[RAILS_ENV].symbolize_keys
    [:compress, :encrypt].each{|key| @fu_conf[key] = @fu_conf[key].symbolize_keys if @fu_conf[key]}

    amazon_s3_yaml = File.join(RAILS_ROOT, 'config', 'amazon_s3.yml')
    if File.exist?(amazon_s3_yaml)
      @s3_conf = YAML.load_file(amazon_s3_yaml)[RAILS_ENV].symbolize_keys
      @fu_conf[:s3_bucket] ||= @s3_conf[:bucket_name]
      @fu_conf[:aws_access_key_id] ||= @s3_conf[:access_key_id]
      @fu_conf[:aws_secret_access_key] ||= @s3_conf[:secret_access_key]
    end

    @timestamp = datetime_formatted
    @verbose = @fu_conf.has_key?(:verbose)

    apply_defaults
    check_conf
    create_dirs
  end

  def sqlcmd_options
    opts = []

    opts << "--socket=#{@db_conf[:socket]}" if @db_conf.has_key?(:socket)
    opts << "--host=#{@db_conf[:host]}" if @db_conf.has_key?(:host) && (@db_conf[:host] != 'localhost')
    opts << "--port=#{@db_conf[:port]}" if @db_conf.has_key?(:port)
    opts << "--user=#{@db_conf[:username]}" unless @db_conf[:username].blank?

    if !@db_conf[:password].blank? && @db_conf[:adapter] != 'postgresql'
      opts << "--password=#{@db_conf[:password]}"
    end

    opts.join(' ')
  end

  def pgpassword_prefix
    if !@db_conf[:password].blank? 
      "PGPASSWORD=#{@db_conf[:password]}"
    end
  end

  def dump
    self.archive_path = File.join(dump_base_path, db_dump_filename)
    case @db_conf[:adapter]
    when 'postgresql'
      cmd = niceify "#{pgpassword_prefix} #{db_dump_cmd} -i -F c -b #{sqlcmd_options} #{@db_conf[:database]} > #{self.archive_path}"
    when 'mysql'
      cmd = niceify "#{db_dump_cmd} #{@fu_conf[:mysqldump_options]} #{sqlcmd_options} #{@db_conf[:database]} > #{self.archive_path}"
    end
    puts cmd if @verbose
    `#{cmd}`

    compress_db() if @fu_conf[:compress]
    encrypt_archive() if @fu_conf[:encrypt]
  end

  def backup
    dump()
    store_file(self.archive_path, @fu_conf[:s3_db_prefix])
  end

  def list_backups
    s3_bucket.keys.map(&:to_s).reject{|e| e =~ /\_\$folder\$/}
  end

  # Don't count on being able to drop the database, but do expect to drop all tables
  def prepare_db_for_restore
    raise "restore unimplemented for #{adapter}" unless (adapter = @db_conf[:adapter]) == 'postgresql'
    query = "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'"
    cmd = "psql #{@db_conf[:database]} -t -c \"#{query}\""
    puts "Executing: '#{cmd}'"
    tables = `#{cmd}`

    query = "DROP TABLE #{tables.map(&:chomp).map(&:strip).reject(&:empty?).join(", ")} CASCADE"
    cmd = "psql #{@db_conf[:database]} -t -c \"#{query}\""
    puts "Executing: '#{cmd}'"
    `#{cmd}`
  end

  def restore_backup(key)
    raise "Restore not implemented for #{@db_conf[:adapter]}" unless @db_conf[:adapter] == 'postgresql'
    raise 'Restore not implemented for zip' if @fu_conf[:compress][:prog] == 'zip'

    restore_file_name = @fu_conf[:compress] ? compressed_filename('restore.sql') : 'restore.sql'
    restore_file = Tempfile.new(restore_file_name)

    open(restore_file.path, 'w') do |fh|
      puts "Fetching #{key} to #{restore_file.path}"
      s3_connection.bucket(@fu_conf[:s3_bucket]).get(key) do |chunk|
        fh.write chunk
      end
    end

    if(@fu_conf[:compress])
      restore_file_unpacked = Tempfile.new('restore.sql')
      cmd = niceify "tar xfz #{restore_file.path} -O > #{restore_file_unpacked.path}"
      puts "\nUntar: #{cmd}\n" if @verbose
      `#{cmd}`
    else
      restore_file_unpacked = restore_file
    end

    prepare_db_for_restore

    # Do the actual restore
    case @db_conf[:adapter]
    when 'postgresql'
      cmd = niceify "export #{pgpassword_prefix} && #{restore_command_path} --clean #{sqlcmd_options} --dbname=#{@db_conf[:database]} #{restore_file_unpacked.path}"
    # when 'mysql'
    #   raise "restore unimplemented for #{}
    #   cmd = niceify "mysql command goes here"
    end
    puts "\nRestore: #{cmd}\n" if @verbose
    `#{cmd}`
  end

  ## Static-file Dump/Backup methods
  def dump_static_files
    if !@fu_conf[:static_paths]
      raise BackupFuConfigError, 'No static paths are defined in config/backup_fu.yml.  See README.'
    end
    paths = @fu_conf[:static_paths].split(' ')
    self.archive_path = initial_static_archive_path
    compress_static(paths) # always compress these paths into an archive
    encrypt_archive() if @fu_conf[:encrypt]
  end

  def backup_static
    dump_static_files()
    store_file(self.archive_path, @fu_conf[:s3_static_prefix])
  end

  def cleanup
    count = @fu_conf[:keep_backups].to_i
    db_backups = Dir.glob("#{dump_base_path}/*.sql*").sort{|a,b| File.mtime(a) <=> File.mtime(b)}
    if count >= db_backups.length
      puts "No old db_backups to cleanup"
    else
      puts "Keeping most recent #{count} out of #{db_backups.length} total db_backups"
      files_to_remove = db_backups - db_backups.last(count)
      files_to_remove.each {|f| File.unlink(f)}
    end
  end

  private

  def s3_connection
    @s3 ||= RightAws::S3.new(@fu_conf[:aws_access_key_id], @fu_conf[:aws_secret_access_key])
  end
  def s3_bucket
    @s3_bucket ||= s3_connection.bucket(@fu_conf[:s3_bucket], true, 'private')
  end

  def store_file(file, s3_prefix = nil)
    s3_key = "#{s3_prefix}#{File.basename(file)}"
    puts "\nBacking up to S3: #{s3_key}\n" if @verbose
    key = s3_bucket.key(s3_key)
    key.data = open(file)
    key.put(nil, 'private')
  end

  def apply_defaults
    # Override access keys with environment variables:
    @fu_conf[:s3_prefix] ||= ''
    @fu_conf[:s3_bucket] = ENV['s3_bucket'] unless ENV['s3_bucket'].blank?
    if ENV.keys.include?('AMAZON_ACCESS_KEY_ID') && ENV.keys.include?('AMAZON_SECRET_ACCESS_KEY')
      @fu_conf[:aws_access_key_id] = ENV['AMAZON_ACCESS_KEY_ID']
      @fu_conf[:aws_secret_access_key] = ENV['AMAZON_SECRET_ACCESS_KEY']
    end
    # mysql defaults
    @fu_conf[:mysqldump_options] ||= '--complete-insert --skip-extended-insert'
    # compression defaults to tar-gzip (gzip implied unless compress: false set in the backup_fu.yml file)
    @fu_conf[:compress] ||= {:prog => 'tar'}
    # keep 5 backups around by default
    @fu_conf[:keep_backups] ||= 5
  end
  # raise errors if configuration isn't setup correctly
  def check_conf
    if @fu_conf[:app_name] == 'replace_me'
      raise BackupFuConfigError, 'Application name (app_name) key not set in config/backup_fu.yml.'
    elsif @fu_conf[:s3_bucket] == 'some-s3-bucket'
      raise BackupFuConfigError, 'S3 bucket (s3_bucket) not set in config/backup_fu.yml.  This bucket must be created using an external S3 tool like S3 Browser for OS X, or JetS3t (Java-based, cross-platform).'
    end
    if @fu_conf[:aws_access_key_id].blank? || @fu_conf[:aws_secret_access_key].blank? ||
         @fu_conf[:aws_access_key_id].include?('--replace me') || @fu_conf[:aws_secret_access_key].include?('--replace me')
      raise BackupFuConfigError, 'AWS Access Key Id or AWS Secret Key not set in config/backup_fu.yml.'
    end
    puts "compress, encrypt:"
    p @fu_conf[:compress]
    p @fu_conf[:encrypt]
  end

  def db_dump_cmd
    dump = {:postgresql => 'pg_dump',:mysql => 'mysqldump'}
    # Note: the 'mysqldump_path' config option is DEPRECATED but keeping this in for legacy config file support
    @fu_conf[:mysqldump_path] || @fu_conf[:dump_path] || dump[@db_conf[:adapter].intern]
  end

  def restore_command_path
    command = @fu_conf[:restore_command_path] || ((adapter = @db_conf[:adapter]) == 'postgresql' && 'pg_restore')
    raise "Restore unimplemented for adapter #{adapter}" if command.blank?
    command
  end

  # where to put the dumped files
  def dump_base_path
    @fu_conf[:dump_base_path] || File.join(RAILS_ROOT, 'tmp', 'backup')
  end

  def db_dump_filename
    "#{@fu_conf[:app_name]}_#{ @timestamp }_db.sql"
  end

  def compressed_filename(filename)
    if(@fu_conf[:compress][:prog] == 'zip')
      filename.end_with? '.zip' ? filename : filename + '.zip'
    else
      filename + '.tar'
    end
  end

  def encrypted_filename(filename)
    filename + '.gpg'
  end
  def decrypted_filename(filename)
    if filename =~ /(.+)\.gpg/
      $1
    else
      filename
    end
  end

  def initial_static_archive_path
    if(@fu_conf[:compress][:prog] == 'zip')
      f = "#{@fu_conf[:app_name]}_#{ @timestamp }_static.zip"
    else
      f = "#{@fu_conf[:app_name]}_#{ @timestamp }_static.tar"
    end
    File.join(dump_base_path, f)
  end

  def create_dirs
    ensure_directory_exists(dump_base_path)
  end

  def ensure_directory_exists(dir)
    FileUtils.mkdir_p(dir) unless File.exist?(dir)
  end

  def niceify(cmd)
    if @fu_conf[:enable_nice]
      "nice -n -#{@fu_conf[:nice_level]} #{cmd}"
    else
      cmd
    end
  end

  def datetime_formatted
    Time.now.strftime("%Y-%m-%d") + "_#{ Time.now.tv_sec }"
  end

  def compress_db
    compressed_path = compressed_filename(self.archive_path)

    if(@fu_conf[:compress][:prog] == 'zip')
      cmd = niceify "zip #{zip_switches} #{compressed_path} #{self.archive_path}"
      puts "\nZip: #{cmd}\n" if @verbose
      `#{cmd}`
    else # TAR it up
      cmd = niceify "tar -czf #{compressed_path} -C #{File.dirname(self.archive_path)} #{File.basename(self.archive_path)}"
      puts "\nTar: #{cmd}\n" if @verbose
      `#{cmd}`
    end

    # remove original dump file, set new archive_path
    File.unlink self.archive_path
    self.archive_path = compressed_path
  end

  def compress_static(paths)
    paths.collect!{|p| p.first == '/' ? p : File.join(RAILS_ROOT, p)}
    if @fu_conf[:compress][:prog] == 'tar'
      # tar and compress with gzip
      cmd = niceify "tar -czf #{self.archive_path}.gz #{paths.join(' ')}"
      puts "Tar: #{cmd}\n" if @verbose
      `#{cmd}`
      self.archive_path += ".gz"
    else
      # add each path to archive
      paths.each do |p|
        puts "Static Path: #{p}" if @verbose
        if @fu_conf[:compress][:prog] == 'zip'
          cmd = niceify "zip -r #{zip_switch} #{self.archive_path} #{p}"
          puts "\nZip: #{cmd}\n" if @verbose
          `#{cmd}`
       end
      end
    end
  end

  # Currently only aware of gpg
  def encrypt_archive()
    file_path_orig = self.archive_path.dup
    cmd = niceify "gpg -e -r '#{@fu_conf[:encrypt][:user]}' #{file_path_orig}"
    puts "\nGPG: #{cmd}" if @verbose
    `#{cmd}`

    # remove original dump file, set the new archive_path
    File.unlink file_path_orig
    self.archive_path = encrypted_filename(self.archive_path)
  end

  # returns: new file path
  # currently only aware of gpg
  def unencrypt_file(file_path)
    decrypted_file_path = decrypted_filename(file_path)
    cmd = niceify "gpg -o #{decrypted_file_path} --decrypt #{file_path}"
    puts "\nGPG: #{cmd}" if @verbose
    `#{cmd}`
    File.unlink file_path
    decrypted_file_path
  end

  # Add -j option to keep from preserving directory structure
  def zip_switches
    if(@fu_conf[:zip_password] && !@fu_conf[:zip_password].blank?)
      password_option = "-P #{@fu_conf[:zip_password]}"
    else
      password_option = ''
    end

    "-j #{password_option}"
  end

  def skips
    return '' unless @fu_conf[:skips]

    raise BackupFuConfigError, 'skip option is not array or string' unless @fu_conf[:skips].kind_of?(Array) || @fu_conf[:skips].kind_of?(String)

    if @fu_conf[:skips].kind_of?(Array)
      @fu_conf[:skips].collect{|skip| " --exclude=#{skip} " }.join
    else
      @fu_conf[:skips]
    end
  end
end
