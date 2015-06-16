class AddTicketFields < ActiveRecord::Migration
  def self.up
    add_column :casserver_tgt, :token, :string
    add_column :casserver_tgt, :user_id, :integer
    add_column :casserver_tgt, :nickname, :string
    add_index :casserver_tgt, :token
    add_index :casserver_tgt, :user_id
    add_index :casserver_tgt, :nickname
  end # self.up

  def self.down
    remove_column :casserver_tgt, :token
    remove_column :casserver_tgt, :user_id
    remove_column :casserver_tgt, :nickname
    remove_index :casserver_tgt, :token
    remove_index :casserver_tgt, :user_id
    remove_index :casserver_tgt, :nickname
  end # self.down
end