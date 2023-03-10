<?php
/*
  Secure random number generator.
 
 */
class PRNG
{
	const rng_psize = 256;
	
	private $i = 0;
	private $j = 0;
	private $S = array();
	
	public function __construct()
	{
	}
	
	public function init($key)
	{
		for($i = 0; $i < 256; ++$i)
			$this->S[$i] = $i;
		$j = 0;
		for($i = 0; $i < 256; ++$i) 
		{
			$j = ($j + $this->S[$i] + $key[$i % count($key)]) & 255;
			$t = $this->S[$i];
			$this->S[$i] = $this->S[$j];
			$this->S[$j] = $t;
		}
		$this->i = 0;
		$this->j = 0;		
	}
	
	public function next() 
	{
		$this->i = ($this->i + 1) & 255;
		$this->j = ($this->j + $this->S[$this->i]) & 255;
		$t = $this->S[$this->i];
		$this->S[$this->i] = $this->S[$this->j];
		$this->S[$this->j] = $t;
		return $this->S[($t + $this->S[$this->i]) & 255];
	}
}
?>
