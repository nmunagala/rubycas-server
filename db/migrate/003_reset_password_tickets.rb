class ResetPasswordTickets < ActiveRecord::Migration
  def self.up
    create_table 'casserver_rpt', :force => true do |t|
      t.string    'ticket',          :null => false
      t.timestamp 'created_on',      :null => false
      t.datetime  'consumed',        :null => true
      t.string    'username',        :null => false
      t.string    'client_hostname', :null => false
    end
  end # self.up

  def self.down
    drop_table 'casserver_rpt'
  end # self.down
end
