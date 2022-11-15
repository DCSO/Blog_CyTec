rule hz_rat
{
  strings:
      $x_mutex = "91E99696-92CC-43F4-99B0-774D80BDAA6B"
      $x_pdb_path_2_8_2__and_2_9_0 = "D:\\WORKSPACE\\HZ_"
      $x_pdb_path_2_9_1  = "D:\\WORKSPACE\\HP\\HZ_"
      $x_pdf_path ="C:\\Users\\dell\\source\\repos\\WindowsProject2\\Release\\WindowsProject1.pdb"
      $x_pdb_path_short_part = "hp_client_win"
      $x_wrongly_written_error_msg = "instanse already exist."      
  condition:
      any of them
}
